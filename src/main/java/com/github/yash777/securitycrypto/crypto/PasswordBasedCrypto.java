package com.github.yash777.securitycrypto.crypto;

import com.github.yash777.securitycrypto.exception.CryptoOperationException;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Password-based AES-CBC encryption using PBKDF2 key derivation — Java 8 compatible.
 *
 * <p>Generalises {@code CryptoService.encode()} from the MyWorld project into a
 * reusable, configurable class that supports three IV strategies:
 *
 * <table border="1" summary="IV strategies" cellpadding="4">
 *   <tr><th>Method pair</th><th>Wire format</th><th>Deterministic?</th></tr>
 *   <tr>
 *     <td>{@link #encryptWithRandomIv} / {@link #decryptWithRandomIv}</td>
 *     <td>{@code Base64( IV(16B) || ciphertext )}</td>
 *     <td>No — recommended for new code</td>
 *   </tr>
 *   <tr>
 *     <td>{@link #encryptWithDateIv} / {@link #decryptWithDateIv}</td>
 *     <td>{@code Base64( ciphertext )} — IV re-derived from date on both sides</td>
 *     <td>Yes — clean output, date must be shared</td>
 *   </tr>
 *   <tr>
 *     <td>{@link #encryptWithSaltIvPrefix} / {@link #decryptWithSaltIvPrefix}</td>
 *     <td>{@code Base64( saltBytes(N) || IV(16B) || ciphertext )} — exact CryptoService layout</td>
 *     <td>Yes — date not needed on decrypt (IV is in the buffer)</td>
 *   </tr>
 * </table>
 *
 * <h2>Why encryptWithDateIv and encryptWithSaltIvPrefix differ</h2>
 * <p>Both use the same PBKDF2 key and the same date-derived IV bytes, so the raw
 * AES ciphertext is <em>identical</em>. The only difference is what gets prepended:
 * <pre>
 *   encryptWithDateIv()       → Base64( ciphertext )                          ← clean
 *   encryptWithSaltIvPrefix() → Base64( salt(N) || IV(16) || ciphertext )     ← full CryptoService layout
 *
 *   Example (salt="Yash@gmail.com", date="2023-12-29T10:09:34", password="Yash@001"):
 *     encryptWithDateIv()       → "/od2rFy3shnMt2ehEQdUJA=="
 *     encryptWithSaltIvPrefix() → "WWFzaEBnbWFpbC5jb20yMDIzLTEyLTI5VDEwOjA5/od2rFy3shnMt2ehEQdUJA=="
 *                                   
 *                             ───────────────────────────────────────────────────────────────────────────
 *                                WWFzaEBnbWFpbC5jb20  2MDIzLTEyLTI5VDEwOjA5  /od2rFy3shnMt2ehEQdUJA==
 *                                ↑ "Yash@gmail.com"    ↑ "2023-12-29T10:09"    ↑ actual ciphertext
 *                                   (salt — 14 B)           (IV — 16 B)           (same in both)
 *                             ───────────────────────────────────────────────────────────────────────────
 * </pre>
 *
 * <h2>Key derivation</h2>
 * <p>The passphrase is strengthened via PBKDF2 (SHA-1 or SHA-256) before use as an AES key.
 * See <a href="https://stackoverflow.com/a/32583766/5081877">SO 32583766</a> and
 * <a href="https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption">SO 992019</a>.
 *
 * @author  Yash
 * @version 1.0.0
 * @since   1.0.0
 * @see     <a href="https://stackoverflow.com/a/32583766/5081877">SO 32583766 — password-based AES</a>
 * @see     <a href="https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption">SO 992019</a>
 * @see     <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">javax.crypto.Cipher</a>
 */
public class PasswordBasedCrypto {

    private static final Logger log = LoggerFactory.getLogger(PasswordBasedCrypto.class);

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /** Default date format used to derive an IV string from a {@link Date}. Matches the pattern in CryptoService. */
    public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    /** AES cipher transformation used for all encrypt/decrypt operations. */
    public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    /** AES algorithm name used in {@link SecretKeySpec}. */
    public static final String AES_ALGORITHM = "AES";

    /** IV length in bytes required by AES-CBC (one AES block = 16 bytes). */
    public static final int IV_LENGTH = 16;

    // -----------------------------------------------------------------------
    // Algorithm enum
    // -----------------------------------------------------------------------

    /**
     * PBKDF2 key-derivation algorithm variants.
     *
     * <p>{@link #PBKDF2_HMAC_SHA1} matches {@code EncoderConstants.PBKDF2_ALGORITHM}
     * in the original {@code CryptoService}. {@link #PBKDF2_HMAC_SHA256} is the
     * recommended choice for all new code.
     */
    public enum Algorithm {

        /**
         * PBKDF2 with HMAC-SHA-1 — legacy; matches original CryptoService settings.
         * Produces a 128-bit or 256-bit AES key.
         */
        PBKDF2_HMAC_SHA1("PBKDF2WithHmacSHA1"),

        /**
         * PBKDF2 with HMAC-SHA-256 — recommended for new code.
         * Stronger hash function; produces a 128-bit or 256-bit AES key.
         */
        PBKDF2_HMAC_SHA256("PBKDF2WithHmacSHA256");

        /** JCE algorithm name passed to {@link SecretKeyFactory#getInstance(String)}. */
        public final String jceName;

        Algorithm(String jceName) {
            this.jceName = jceName;
        }
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /** Number of PBKDF2 iterations. Higher = slower = stronger against brute force. */
    private final int iterations;

    /** Derived AES key length in bits (128 or 256). */
    private final int keyLengthBits;

    /** PBKDF2 algorithm to use. */
    private final Algorithm algorithm;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Creates a {@code PasswordBasedCrypto} with recommended defaults:
     * PBKDF2-HMAC-SHA256, 65536 iterations, 256-bit key.
     */
    public PasswordBasedCrypto() {
        this(Algorithm.PBKDF2_HMAC_SHA256, 65536, 256);
    }

    /**
     * Full constructor for explicit PBKDF2 settings.
     *
     * @param algorithm     PBKDF2 variant
     * @param iterations    iteration count (use 1024 for CryptoService compatibility)
     * @param keyLengthBits AES key length in bits (128 or 256)
     */
    public PasswordBasedCrypto(Algorithm algorithm, int iterations, int keyLengthBits) {
        this.algorithm     = algorithm;
        this.iterations    = iterations;
        this.keyLengthBits = keyLengthBits;
    }

    /**
     * Factory for exact {@code CryptoService} compatibility:
     * PBKDF2-HMAC-SHA1, 1024 iterations, 128-bit key.
     *
     * @return legacy-mode instance
     */
    public static PasswordBasedCrypto legacyMode() {
        return new PasswordBasedCrypto(Algorithm.PBKDF2_HMAC_SHA1, 1024, 128);
    }

    // -----------------------------------------------------------------------
    // Strategy 1 — Random IV (recommended)
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code data} with a cryptographically random IV.
     *
     * <p>Wire format: {@code Base64( IV(16B) || ciphertext )}
     * The IV is embedded — the receiver only needs the passphrase and salt.
     *
     * @param data       plaintext to encrypt
     * @param passphrase PBKDF2 passphrase (e.g. the master key)
     * @param salt       per-record salt (e.g. username); unique per record, not secret
     * @return Base64-encoded {@code IV || ciphertext}
     * @throws CryptoOperationException if encryption fails
     */
    public String encryptWithRandomIv(String data, String passphrase, String salt) {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        byte[] cipherBytes = doEncrypt(data, passphrase, salt.getBytes(UTF_8), iv);

        byte[] payload = new byte[IV_LENGTH + cipherBytes.length];
        System.arraycopy(iv,          0, payload, 0,         IV_LENGTH);
        System.arraycopy(cipherBytes, 0, payload, IV_LENGTH, cipherBytes.length);

        String result = Base64.getEncoder().encodeToString(payload);
        log.debug("encryptWithRandomIv: plainLen={} outputLen={}", data.length(), result.length());
        return result;
    }

    /**
     * Decrypts a payload produced by {@link #encryptWithRandomIv}.
     *
     * <p>Extracts the first 16 bytes as the IV, decrypts the remainder.
     *
     * @param encryptedBase64 Base64 string from {@code encryptWithRandomIv}
     * @param passphrase      same passphrase used during encryption
     * @param salt            same salt used during encryption
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if payload is malformed or credentials are wrong
     */
    public String decryptWithRandomIv(String encryptedBase64, String passphrase, String salt)
            throws InvalidCiphertextException {

        byte[] payload = decodeBase64Safe(encryptedBase64);
        if (payload.length <= IV_LENGTH) {
            throw new InvalidCiphertextException(
                    "Payload too short — expected >" + IV_LENGTH + " bytes but got " + payload.length);
        }
        byte[] iv          = Arrays.copyOfRange(payload, 0, IV_LENGTH);
        byte[] cipherBytes = Arrays.copyOfRange(payload, IV_LENGTH, payload.length);
        return doDecrypt(cipherBytes, passphrase, salt.getBytes(UTF_8), iv);
    }

    // -----------------------------------------------------------------------
    // Strategy 2 — Date-derived IV (clean output, deterministic)
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code data} with an IV derived from {@code date}.
     *
     * <p>Wire format: {@code Base64( ciphertext )} — the IV is <em>not</em> stored in
     * the output; both sides re-derive it from the same date. Use
     * {@link #decryptWithDateIv(String, String, String, Date)} to decrypt.
     *
     * <p>The IV is the first 16 UTF-8 bytes of the date formatted as
     * {@value #DEFAULT_DATE_FORMAT}, e.g. {@code "2023-12-29T10:09:34"} → IV = {@code "2023-12-29T10:09"}.
     *
     * @param data       plaintext to encrypt
     * @param passphrase PBKDF2 passphrase
     * @param salt       per-record salt (e.g. username)
     * @param date       record creation date used to derive the IV
     * @return Base64-encoded ciphertext only (no IV prefix)
     * @throws CryptoOperationException if encryption fails
     */
    public String encryptWithDateIv(String data, String passphrase, String salt, Date date) {
        return encryptWithDateIv(data, passphrase, salt, date, DEFAULT_DATE_FORMAT);
    }

    /**
     * Encrypts using a date-derived IV with a custom date format.
     *
     * @param data       plaintext to encrypt
     * @param passphrase PBKDF2 passphrase
     * @param salt       per-record salt
     * @param date       date used to derive the IV
     * @param dateFormat {@link SimpleDateFormat} pattern
     * @return Base64-encoded ciphertext only
     */
    public String encryptWithDateIv(String data, String passphrase, String salt,
                                    Date date, String dateFormat) {
        byte[] iv          = ivFromDate(date, dateFormat);
        byte[] cipherBytes = doEncrypt(data, passphrase, salt.getBytes(UTF_8), iv);
        String result      = Base64.getEncoder().encodeToString(cipherBytes);
        log.debug("encryptWithDateIv: date={} plainLen={} outputLen={}",
                formatDate(date, dateFormat), data.length(), result.length());
        return result;
    }

    /**
     * Encrypts using an IV derived from a date string (convenience overload).
     *
     * @param data        plaintext to encrypt
     * @param passphrase  PBKDF2 passphrase
     * @param salt        per-record salt
     * @param dateString  date string in {@value #DEFAULT_DATE_FORMAT}
     * @return Base64-encoded ciphertext only
     */
    public String encryptWithDateIv(String data, String passphrase, String salt, String dateString) {
        Date date = parseDate(dateString, DEFAULT_DATE_FORMAT);
        return encryptWithDateIv(data, passphrase, salt, date);
    }

    /**
     * Decrypts a payload produced by {@link #encryptWithDateIv(String, String, String, Date)}.
     *
     * <p>Re-derives the IV from {@code date} — the date must be the same one used during encryption.
     *
     * @param encryptedBase64 Base64 ciphertext from {@code encryptWithDateIv}
     * @param passphrase      same passphrase used during encryption
     * @param salt            same salt used during encryption
     * @param date            same date used during encryption
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if decryption fails
     */
    public String decryptWithDateIv(String encryptedBase64, String passphrase, String salt, Date date)
            throws InvalidCiphertextException {
        return decryptWithDateIv(encryptedBase64, passphrase, salt, date, DEFAULT_DATE_FORMAT);
    }

    /**
     * Decrypts using a date-derived IV with a custom date format.
     *
     * @param encryptedBase64 Base64 ciphertext
     * @param passphrase      PBKDF2 passphrase
     * @param salt            per-record salt
     * @param date            date used during encryption
     * @param dateFormat      {@link SimpleDateFormat} pattern used during encryption
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if decryption fails
     */
    public String decryptWithDateIv(String encryptedBase64, String passphrase, String salt,
                                    Date date, String dateFormat) throws InvalidCiphertextException {
        byte[] iv          = ivFromDate(date, dateFormat);
        byte[] cipherBytes = decodeBase64Safe(encryptedBase64);
        return doDecrypt(cipherBytes, passphrase, salt.getBytes(UTF_8), iv);
    }

    /**
     * Decrypts using an IV derived from a date string (convenience overload).
     *
     * @param encryptedBase64 Base64 ciphertext
     * @param passphrase      PBKDF2 passphrase
     * @param salt            per-record salt
     * @param dateString      date string in {@value #DEFAULT_DATE_FORMAT}
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if decryption fails
     */
    public String decryptWithDateIv(String encryptedBase64, String passphrase, String salt,
                                    String dateString) throws InvalidCiphertextException {
        Date date = parseDate(dateString, DEFAULT_DATE_FORMAT);
        return decryptWithDateIv(encryptedBase64, passphrase, salt, date);
    }

    // -----------------------------------------------------------------------
    // Strategy 3 — CryptoService full wire-format: salt || IV || ciphertext
    // -----------------------------------------------------------------------

    /**
     * Encrypts in the <strong>exact wire format</strong> of {@code CryptoService.encode()}.
     *
     * <h3>Buffer layout</h3>
     * <pre>
     *   Base64( saltBytes(N) || ivBytes(16) || ciphertext )
     *           ^username         ^date-IV
     * </pre>
     *
     * <h3>CryptoService code reproduced</h3>
     * <pre>
     *   // IV from date string (first 16 bytes)
     *   byte[] ivBytes = new byte[16];
     *   System.arraycopy(dateString.getBytes("UTF-8"), 0, ivBytes, 0, 16);
     *
     *   // Init cipher — re-read IV from getParameters() (same value, confirms what cipher uses)
     *   cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivBytes));
     *   ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
     *
     *   byte[] ciphertext = cipher.doFinal(rawPass.getBytes("UTF-8"));
     *
     *   // Assemble: salt || iv || ciphertext
     *   byte[] buffer = new byte[saltBytes.length + ivBytes.length + ciphertext.length];
     *   System.arraycopy(saltBytes,  0, buffer, 0, saltBytes.length);
     *   System.arraycopy(ivBytes,    0, buffer, saltBytes.length, ivBytes.length);
     *   System.arraycopy(ciphertext, 0, buffer, saltBytes.length + ivBytes.length, ciphertext.length);
     *   return Base64.encode(buffer);
     * </pre>
     *
     * <h3>Why the two outputs differ for the same inputs</h3>
     * <pre>
     *   encryptWithDateIv()       → "/od2rFy3shnMt2ehEQdUJA=="
     *   encryptWithSaltIvPrefix() → "WWFzaEBnbWFpbC5jb20yMDIzLTEyLTI5VDEwOjA5/od2rFy3shnMt2ehEQdUJA=="
     *                                 ← "Yash@gmail.com" + "2023-12-29T10:09" + same ciphertext →
     *                             ───────────────────────────────────────────────────────────────────────────
     *                                WWFzaEBnbWFpbC5jb20  2MDIzLTEyLTI5VDEwOjA5  /od2rFy3shnMt2ehEQdUJA==
     *                                ↑ "Yash@gmail.com"    ↑ "2023-12-29T10:09"    ↑ actual ciphertext
     *                                   (salt — 14 B)           (IV — 16 B)           (same in both)
     *                             ───────────────────────────────────────────────────────────────────────────
     * </pre>
     *
     * @param rawPass    the plaintext password to encrypt
     * @param passphrase the PBKDF2 master passphrase (e.g. {@code CryptoService.key})
     * @param salt       per-user salt / username — prepended to output AND used as PBKDF2 salt
     * @param date       record creation date; first 16 UTF-8 bytes of formatted string = IV
     * @return Base64-encoded {@code saltBytes || IV(16B) || ciphertext}
     * @throws CryptoOperationException if encryption fails
     * @see #decryptWithSaltIvPrefix(String, String, String)
     */
    public String encryptWithSaltIvPrefix(String rawPass, String passphrase, String salt, Date date) {
        return encryptWithSaltIvPrefix(rawPass, passphrase, salt, date, DEFAULT_DATE_FORMAT);
    }

    /**
     * Encrypts in the CryptoService wire format using a custom date pattern.
     *
     * @param rawPass    plaintext to encrypt
     * @param passphrase PBKDF2 master passphrase
     * @param salt       per-user salt (username) — prepended to output
     * @param date       creation date for IV derivation
     * @param dateFormat {@link SimpleDateFormat} pattern
     * @return Base64-encoded {@code saltBytes || IV(16B) || ciphertext}
     */
    public String encryptWithSaltIvPrefix(String rawPass, String passphrase, String salt,
                                             Date date, String dateFormat) {
        try {
            byte[] saltBytes = salt.getBytes(UTF_8);

            // Step 1 — IV from date string (first 16 UTF-8 bytes)
            byte[] ivBytes   = new byte[IV_LENGTH];
            byte[] dateBytes = new SimpleDateFormat(dateFormat).format(date).getBytes(UTF_8);
            System.arraycopy(dateBytes, 0, ivBytes, 0, Math.min(dateBytes.length, IV_LENGTH));

            // Step 2 — Derive PBKDF2 key (passphrase = master key, salt = username bytes)
            SecretKey key = deriveKey(passphrase, saltBytes);

            // Step 3 — Init cipher and re-read IV from cipher.getParameters()
            //          (matches CryptoService exactly — same value confirmed from cipher state)
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            AlgorithmParameters params = cipher.getParameters();
            ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();

            // Step 4 — Encrypt
            byte[] ciphertext = cipher.doFinal(rawPass.getBytes(UTF_8));

            // Step 5 — Assemble: saltBytes || ivBytes(16) || ciphertext
            byte[] buffer = new byte[saltBytes.length + IV_LENGTH + ciphertext.length];
            System.arraycopy(saltBytes, 0, buffer, 0,                            saltBytes.length);
            System.arraycopy(ivBytes,   0, buffer, saltBytes.length,             IV_LENGTH);
            System.arraycopy(ciphertext,0, buffer, saltBytes.length + IV_LENGTH, ciphertext.length);

            String result = Base64.getEncoder().encodeToString(buffer);
            log.debug("encryptWithSaltIvPrefix: salt={} date={} outputLen={}",
                    salt, formatDate(date, dateFormat), result.length());
            return result;

        } catch (Exception e) {
            throw new CryptoOperationException(
                    "encryptWithSaltIvPrefix failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a payload produced by {@link #encryptWithSaltIvPrefix}.
     *
     * <p>Extracts the IV from its known position in the buffer — the original date
     * is <strong>not</strong> needed because the IV is already embedded.
     *
     * <h3>Buffer layout assumed</h3>
     * <pre>
     *   decoded[0 .. saltLen)              = salt bytes (skipped)
     *   decoded[saltLen .. saltLen+16)     = IV bytes   (extracted)
     *   decoded[saltLen+16 .. end)         = ciphertext (decrypted)
     * </pre>
     *
     * @param encodedBase64 Base64 string from {@code encryptWithSaltIvPrefix}
     * @param passphrase    PBKDF2 master passphrase (same as used during encryption)
     * @param salt          username — needed to calculate where the salt prefix ends
     * @return decrypted plaintext
     * @throws InvalidCiphertextException if the payload is malformed or credentials are wrong
     */
    public String decryptWithSaltIvPrefix(String encodedBase64, String passphrase, String salt)
            throws InvalidCiphertextException {

        byte[] buffer    = decodeBase64Safe(encodedBase64);
        byte[] saltBytes = salt.getBytes(UTF_8);
        int    saltLen   = saltBytes.length;

        if (buffer.length <= saltLen + IV_LENGTH) {
            throw new InvalidCiphertextException(
                    "CryptoService payload too short: expected >" + (saltLen + IV_LENGTH)
                    + "B but got " + buffer.length);
        }

        // Extract IV and ciphertext from their fixed positions
        byte[] ivBytes     = Arrays.copyOfRange(buffer, saltLen, saltLen + IV_LENGTH);
        byte[] cipherBytes = Arrays.copyOfRange(buffer, saltLen + IV_LENGTH, buffer.length);

        return doDecrypt(cipherBytes, passphrase, saltBytes, ivBytes);
    }

    // -----------------------------------------------------------------------
    // Date utility methods (public helpers)
    // -----------------------------------------------------------------------

    /**
     * Parses a date string using the given pattern.
     *
     * @param dateString the string to parse
     * @param format     {@link SimpleDateFormat} pattern
     * @return the parsed {@link Date}
     * @throws CryptoOperationException if parsing fails
     */
    public static Date parseDate(String dateString, String format) {
        try {
            return new SimpleDateFormat(format).parse(dateString);
        } catch (ParseException e) {
            throw new CryptoOperationException(
                    "Cannot parse date '" + dateString + "' with format '" + format + "'", e);
        }
    }

    /**
     * Formats a {@link Date} using the given pattern.
     *
     * @param date   the date to format
     * @param format {@link SimpleDateFormat} pattern
     * @return formatted date string
     */
    public static String formatDate(Date date, String format) {
        return new SimpleDateFormat(format).format(date);
    }

    // -----------------------------------------------------------------------
    // Internal — key derivation and cipher operations
    // -----------------------------------------------------------------------

    /**
     * Derives an AES key from {@code passphrase} and raw {@code saltBytes} via PBKDF2.
     *
     * @param passphrase PBKDF2 password (the master key string)
     * @param saltBytes  raw salt bytes (typically {@code username.getBytes(UTF_8)})
     * @return derived AES {@link SecretKey}
     * @throws CryptoOperationException if the algorithm is unavailable
     */
    private SecretKey deriveKey(String passphrase, byte[] saltBytes) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm.jceName);
            PBEKeySpec spec = new PBEKeySpec(
                    passphrase.toCharArray(), saltBytes, iterations, keyLengthBits);
            SecretKey tmp = factory.generateSecret(spec);
            spec.clearPassword(); // defensive: clear passphrase from memory
            return new SecretKeySpec(tmp.getEncoded(), AES_ALGORITHM);
        } catch (Exception e) {
            throw new CryptoOperationException(
                    "PBKDF2 key derivation failed [" + algorithm.jceName + "]: " + e.getMessage(), e);
        }
    }

    /**
     * Performs raw AES-CBC encryption.
     *
     * @param plaintext  UTF-8 string to encrypt
     * @param passphrase PBKDF2 passphrase
     * @param saltBytes  raw salt bytes
     * @param iv         16-byte IV
     * @return raw ciphertext bytes
     */
    private byte[] doEncrypt(String plaintext, String passphrase, byte[] saltBytes, byte[] iv) {
        try {
            SecretKey key = deriveKey(passphrase, saltBytes);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext.getBytes(UTF_8));
        } catch (Exception e) {
            throw new CryptoOperationException("AES encrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * Performs raw AES-CBC decryption.
     *
     * @param cipherBytes raw ciphertext
     * @param passphrase  PBKDF2 passphrase
     * @param saltBytes   raw salt bytes
     * @param iv          16-byte IV
     * @return decrypted plaintext string
     * @throws InvalidCiphertextException if decryption fails
     */
    private String doDecrypt(byte[] cipherBytes, String passphrase, byte[] saltBytes, byte[] iv)
            throws InvalidCiphertextException {
        try {
            SecretKey key = deriveKey(passphrase, saltBytes);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] plain = cipher.doFinal(cipherBytes);
            return new String(plain, UTF_8);
        } catch (Exception e) {
            throw new InvalidCiphertextException(
                    "AES decrypt failed — wrong passphrase/salt/date or corrupted ciphertext: "
                            + e.getMessage(), e);
        }
    }

    /**
     * Derives a 16-byte IV from a {@link Date}: formats the date, takes the first 16 UTF-8 bytes.
     *
     * @param date   source date
     * @param format {@link SimpleDateFormat} pattern
     * @return 16-byte IV array
     */
    private static byte[] ivFromDate(Date date, String format) {
        byte[] dateBytes = new SimpleDateFormat(format).format(date).getBytes(UTF_8);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(dateBytes, 0, iv, 0, Math.min(dateBytes.length, IV_LENGTH));
        return iv;
    }

    /**
     * Decodes a Base64 string, wrapping {@link IllegalArgumentException} as
     * {@link InvalidCiphertextException}.
     *
     * @param base64 input Base64 string
     * @return decoded bytes
     * @throws InvalidCiphertextException if the input is not valid Base64
     */
    private static byte[] decodeBase64Safe(String base64) throws InvalidCiphertextException {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException("Payload is not valid Base64: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Getters for configuration inspection
    // -----------------------------------------------------------------------

    /**
     * Returns the PBKDF2 iteration count configured for this instance.
     *
     * @return number of PBKDF2 iterations
     */
    public int getIterations() { return iterations; }

    /**
     * Returns the AES key length in bits configured for this instance.
     *
     * @return key length in bits (128 or 256)
     */
    public int getKeyLengthBits() { return keyLengthBits; }

    /**
     * Returns the PBKDF2 algorithm configured for this instance.
     *
     * @return the {@link Algorithm} enum value
     */
    public Algorithm getAlgorithm() { return algorithm; }
}
