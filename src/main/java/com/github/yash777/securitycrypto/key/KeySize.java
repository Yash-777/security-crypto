package com.github.yash777.securitycrypto.key;

/**
 * AES key sizes supported by this library.
 *
 * <p>All three sizes are part of the AES standard (FIPS 197).
 * 256-bit keys are preferred for high-security environments.
 * Note: some JVM distributions require the
 * <em>Java Cryptography Extension (JCE) Unlimited Strength</em> policy
 * files to use 192-bit and 256-bit keys. Java 9+ ships with unlimited
 * strength by default.
 *
 * <pre>{@code
 * SecretKey key = KeyManager.generateAesKey(KeySize.AES_256);
 * }</pre>
 *
 * @author Yash
 * @version 1.0.0
 */
public enum KeySize {

    /** 128-bit AES key — always available, good general-purpose choice. */
    AES_128(128),

    /** 192-bit AES key — requires unlimited-strength JCE on Java 8 and below. */
    AES_192(192),

    /** 256-bit AES key — recommended for high-security use. */
    AES_256(256);

    /** Number of bits in this AES key. */
    public final int bits;

    KeySize(int bits) {
        this.bits = bits;
    }

    /**
     * Returns the key length in bytes ({@code bits / 8}).
     *
     * @return key byte length (16, 24, or 32)
     */
    public int bytes() {
        return bits / 8;
    }

    /**
     * Returns the conventional storage file name for this key size,
     * e.g. {@code secret_128bit.key}.
     *
     * @return file name string
     */
    public String fileName() {
        return "secret_" + bits + "bit.key";
    }
}
