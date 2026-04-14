package com.github.yash777.securitycrypto.demo;

import java.text.SimpleDateFormat;
import java.util.Date;

import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto;
import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto.Algorithm;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;

/**
 * Demonstrates all three encryption strategies from {@link PasswordBasedCrypto}
 * using the exact inputs from {@code CryptoService.main()} in the MyWorld project.
 *
 * <h2>The three strategies compared</h2>
 * <pre>
 *  Strategy                  | Wire format                           | Deterministic?
 *  ─────────────────────────────────────────────────────────────────────────────────
 *  encryptWithRandomIv       | Base64( IV(16B) || ciphertext )       | No  (recommended)
 *  encryptWithDateIv         | Base64( ciphertext )                  | Yes (date required to decrypt)
 *  encryptWithSaltIvPrefix   | Base64( salt(N) || IV(16B) || cipher) | Yes (exact CryptoService output)
 * </pre>
 *
 * <h2>Why the outputs differ for the same password</h2>
 * <p>All three use the same AES ciphertext bytes. The difference is what is prepended:
 * <pre>
 *   encryptWithDateIv()       → "/od2rFy3shnMt2ehEQdUJA=="
 *   encryptWithSaltIvPrefix() → "WWFzaEBnbWFpbC5jb20yMDIzLTEyLTI5VDEwOjA5/od2rFy3shnMt2ehEQdUJA=="
 *                                ←── "Yash@gmail.com"(14B) ──→←── "2023-12-29T10:09"(16B) ──→ same ciphertext
 *                             ─────────────────────────────────────────────────────────────────────────────────
 *                                WWFzaEBnbWFpbC5jb20  2MDIzLTEyLTI5VDEwOjA5  /od2rFy3shnMt2ehEQdUJA==
 *                                ↑ "Yash@gmail.com"    ↑ "2023-12-29T10:09"    ↑ actual ciphertext
 *                                   (salt — 14 B)           (IV — 16 B)           (same in both)
 *                             ─────────────────────────────────────────────────────────────────────────────────
 * </pre>
 *
 * @author Yashwanth
 * @see    PasswordBasedCrypto
 */
public class SecurityCryptoTest {

    /**
     * Used as the PBKDF2 password, NOT as an AES key directly.
     */
    private static final String SECRET_PASSWORD_KEY =
            "B&^0QUV^?^SQ.{D|]C[[(+hm'^e7|FJ}Ga-4$T54:(bgpyD,)K{fpE8~M,YMzvu";

    /** Date format matching {@code CryptoService.dateFormat}. */
    private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    /** Creation date string from {@code CryptoService.main()}. */
    private static final String CREATION_DATE_STRING = "2023-12-29T10:09:34";

    /**
     * Entry point — runs all three strategies for both a date-based and a random-IV scenario.
     *
     * @param args not used
     * @throws Exception on any encryption or parsing failure
     */
    public static void main(String[] args) throws Exception {
        // ── PBKDF2 settings matching CryptoService.EncoderConstants ────────────
        //   PBKDF2WithHmacSHA1 · 1024 iterations · 128-bit AES key
        PasswordBasedCrypto pbc = new PasswordBasedCrypto(Algorithm.PBKDF2_HMAC_SHA1, 1024, 128);

        Date enrollDate = new SimpleDateFormat(DATE_FORMAT).parse(CREATION_DATE_STRING);

        // ── Inputs from CryptoService.main() ───────────────────────────────────
        String password = "Yash@001";
        String salt     = "Yash@gmail.com";   // username as PBKDF2 salt

        System.out.println("=== SecurityCryptoTest ===");
        System.out.println("PBKDF2   : " + pbc.getAlgorithm().jceName
                + " · " + pbc.getIterations() + " iter · " + pbc.getKeyLengthBits() + "-bit key");
        System.out.println("Password : " + password);
        System.out.println("Salt     : " + salt);
        System.out.println("Date     : " + CREATION_DATE_STRING);
        System.out.println();

        // ── Strategy 1: Random IV (no date dependency) ─────────────────────────
        System.out.println("── Strategy 1: encryptWithRandomIv ──");
        String ctRandom = pbc.encryptWithRandomIv(password, SECRET_PASSWORD_KEY, salt);
        String ptRandom = pbc.decryptWithRandomIv(ctRandom, SECRET_PASSWORD_KEY, salt);
        System.out.println("  Encrypted : " + ctRandom);
        System.out.println("  Decrypted : " + ptRandom);
        System.out.println("  Format    : Base64( IV(16B) || ciphertext )");
        System.out.println();

        // ── Strategy 2: IV from Date (clean output, date required to decrypt) ──
        System.out.println("── Strategy 2: encryptWithDateIv ──");
        for (int i = 0; i < 2; i++) {
            encryptDecryptWithDate(pbc, password, SECRET_PASSWORD_KEY, salt, enrollDate);
        }
        System.out.println();

        // ── Strategy 3: CryptoService full format (salt + IV + cipher) ─────────
        System.out.println("── Strategy 3: encryptWithSaltIvPrefix ──");
        for (int i = 0; i < 2; i++) {
            encryptDecryptWithSaltIvPrefix(pbc, password, SECRET_PASSWORD_KEY, salt, enrollDate);
        }
        System.out.println();

        // ── Mixed: null date → random IV, non-null date → date IV ──────────────
        System.out.println("── Mixed: ivDate() helper (date vs null) ──");
        for (int i = 0; i < 2; i++) {
            ivDate(pbc, password, SECRET_PASSWORD_KEY, salt, enrollDate);   // with date
            ivDate(pbc, password, SECRET_PASSWORD_KEY, salt, null);         // without date
        }
    }

    // -----------------------------------------------------------------------
    // Strategy 2 helper
    // -----------------------------------------------------------------------

    /**
     * Encrypts and decrypts using {@link PasswordBasedCrypto#encryptWithDateIv}.
     *
     * <p>Output: {@code Base64(ciphertext)} only — IV is re-derived from {@code date} on decrypt.
     *
     * @param pbc        configured {@link PasswordBasedCrypto} instance
     * @param password   the plaintext password to encrypt
     * @param passphrase the PBKDF2 master passphrase
     * @param salt       the per-user salt (username)
     * @param date       record creation date used to derive the IV
     * @throws InvalidCiphertextException if decryption fails
     */
    private static void encryptDecryptWithDate(PasswordBasedCrypto pbc,
            String password, String passphrase, String salt, Date date)
            throws InvalidCiphertextException {

        String encrypted = pbc.encryptWithDateIv(password, passphrase, salt, date);
        String decrypted = pbc.decryptWithDateIv(encrypted, passphrase, salt, date);

        System.out.println("  Encrypt : " + encrypted);
        System.out.println("  Decrypt : " + decrypted + "  [date: " + date + "]");
        System.out.println("  Format  : Base64( ciphertext )  ← no prefix; IV re-derived from date");
    }

    // -----------------------------------------------------------------------
    // Strategy 3 helper
    // -----------------------------------------------------------------------

    /**
     * Encrypts and decrypts using {@link PasswordBasedCrypto#encryptWithSaltIvPrefix}.
     *
     * <p>Output: {@code Base64(saltBytes || IV(16B) || ciphertext)} — exact CryptoService layout.
     * The date is <em>not</em> needed to decrypt because the IV is embedded in the buffer.
     *
     * @param pbc        configured {@link PasswordBasedCrypto} instance
     * @param password   the plaintext password to encrypt
     * @param passphrase the PBKDF2 master passphrase
     * @param salt       the per-user salt (username) — also prepended to output
     * @param date       record creation date used to derive the IV
     * @throws InvalidCiphertextException if decryption fails
     */
    private static void encryptDecryptWithSaltIvPrefix(PasswordBasedCrypto pbc,
            String password, String passphrase, String salt, Date date)
            throws InvalidCiphertextException {

        String encrypted = pbc.encryptWithSaltIvPrefix(password, passphrase, salt, date);
        String decrypted = pbc.decryptWithSaltIvPrefix(encrypted, passphrase, salt);

        System.out.println("  Encrypt : " + encrypted);
        System.out.println("  Decrypt : " + decrypted + "  [date: " + date + "]");
        System.out.println("  Format  : Base64( salt(" + salt.getBytes().length
                + "B) || IV(16B) || ciphertext )");
    }

    // -----------------------------------------------------------------------
    // Mixed helper: null date → random IV, non-null date → date IV
    // -----------------------------------------------------------------------

    /**
     * Encrypts and decrypts using either the date-IV or random-IV strategy depending on
     * whether {@code enrollDate} is null.
     *
     * <ul>
     *   <li>{@code enrollDate != null} → {@link PasswordBasedCrypto#encryptWithDateIv}</li>
     *   <li>{@code enrollDate == null} → {@link PasswordBasedCrypto#encryptWithRandomIv}</li>
     * </ul>
     *
     * @param pbc        configured {@link PasswordBasedCrypto} instance
     * @param password   the plaintext password to encrypt
     * @param passphrase the PBKDF2 master passphrase
     * @param salt       the per-user salt (username)
     * @param enrollDate creation date, or {@code null} for a random IV
     * @throws InvalidCiphertextException if decryption fails
     */
    private static void ivDate(PasswordBasedCrypto pbc,
            String password, String passphrase, String salt, Date enrollDate)
            throws InvalidCiphertextException {

        String encrypted;
        String decrypted;

        if (enrollDate == null) {
            encrypted = pbc.encryptWithRandomIv(password, passphrase, salt);
            decrypted = pbc.decryptWithRandomIv(encrypted, passphrase, salt);
        } else {
            encrypted = pbc.encryptWithDateIv(password, passphrase, salt, enrollDate);
            decrypted = pbc.decryptWithDateIv(encrypted, passphrase, salt, enrollDate);
        }

        System.out.println("  Encrypt:" + encrypted
                + " → Decrypt:" + decrypted
                + " \u27a4 [Date:" + enrollDate + "]");
    }
}