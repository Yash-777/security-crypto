
package com.github.yash777.securitycrypto.demo;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto;
import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto.Algorithm;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;

public class SecurityCryptoTest_OLD {
    /**
     * The master passphrase used in {@code CryptoService.key}.
     * This is the PBKDF2 password — NOT an AES key directly.
     */
    private static final String MASTER_KEY =
            "B&^0QUV^?^SQ.{D|]C[[(+hm'^e7|FJ}Ga-4$T54:(bgpyD,)K{fpE8~M,YMzvu";
    
    /** Date format used by {@code CryptoService.getDateString()} to derive the IV. */
    private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    /**
     * The fixed creation date used in the {@code CryptoService.main()} example.
     * Formatted: {@code "2023-12-29T10:09:34"}
     */
    private static final String CREATION_DATE_STRING = "2023-12-29T10:09:34";
    
	public static void main(String[] args) throws InvalidCiphertextException, ParseException {
		//Random IV — self-contained, recommended
		//PasswordBasedCrypto pbc = new PasswordBasedCrypto();   // SHA-256 · 65536 iter · 256-bit key
		PasswordBasedCrypto pbc = new PasswordBasedCrypto(Algorithm.PBKDF2_HMAC_SHA1, 1024, 128);
//		PasswordBasedCrypto.TRANSFORMATION = "AES/CBC/PKCS5Padding";
//		PasswordBasedCrypto.AES_ALGORITHM = "AES";
		
		
		String ct = pbc.encryptWithRandomIv("secret data", "myPassphrase", "user@example.com");
		String pt = pbc.decryptWithRandomIv(ct,            "myPassphrase", "user@example.com");
		System.out.println(ct + " :: "+ pt);
		
		//String textToEncrypt = "secret data", passphrase = MASTER_KEY, salt = "user@example.com";
		//Date enrollDate = new Date();
		String textToEncrypt = "Yash@001", passphrase = MASTER_KEY, salt = "Yash@gmail.com";
		
		Date enrollDate = new SimpleDateFormat(DATE_FORMAT).parse(CREATION_DATE_STRING);
		for (int i = 0; i < 2; i++) {
			ivDate(pbc, textToEncrypt, passphrase, salt, enrollDate);
			//Encrypt:/od2rFy3shnMt2ehEQdUJA== → Decrypt:Yash@001 ➤ [Date:Fri Dec 29 10:09:34 IST 2023]
			ivDate(pbc, textToEncrypt, passphrase, salt, null);
		}
	}

	private static void ivDate(PasswordBasedCrypto pbc, String encryptedBase64, String passphrase, String salt,
			Date enrollDate) throws InvalidCiphertextException {
		
		// IV from Date — deterministic (CryptoService pattern)
		String encryptIV, decryptIV;
		
		// Encrypt
		if (enrollDate == null) {
			encryptIV = pbc.encryptWithRandomIv(encryptedBase64, passphrase, salt);
		} else {
			encryptIV = pbc.encryptWithDateIv(encryptedBase64, passphrase, salt, enrollDate);
		}
		// Decrypt — IV re-derived from the same date
		if (enrollDate == null) {
			decryptIV = pbc.decryptWithRandomIv(encryptIV, passphrase, salt);
		} else {
			decryptIV = pbc.decryptWithDateIv(encryptIV, passphrase, salt, enrollDate);
		}
		
		System.out.println("Encrypt:" + encryptIV + " → Decrypt:"+ decryptIV+ " ➤ [Date:"+enrollDate+"]");
	}
}
