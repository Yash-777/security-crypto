/**
 * {@code security-crypto} — Java Cryptographic Extension (JCE) library.
 *
 * <p>Provides a clean, exception-safe API for AES symmetric encryption
 * (ECB, CBC, GCM modes), RSA asymmetric encryption, and hybrid
 * RSA + AES-GCM encryption for arbitrary payload sizes.
 *
 * <h2>Packages</h2>
 * <ul>
 *   <li>{@code com.github.yash777.securitycrypto} — {@link com.github.yash777.securitycrypto.CryptoFacade} entry point</li>
 *   <li>{@code com.github.yash777.securitycrypto.cipher} — {@link com.github.yash777.securitycrypto.cipher.AesCipher},
 *       {@link com.github.yash777.securitycrypto.cipher.RsaCipher},
 *       {@link com.github.yash777.securitycrypto.cipher.HybridCipher},
 *       {@link com.github.yash777.securitycrypto.cipher.CipherMode}</li>
 *   <li>{@code com.github.yash777.securitycrypto.key} — {@link com.github.yash777.securitycrypto.key.KeyManager},
 *       {@link com.github.yash777.securitycrypto.key.KeySize}</li>
 *   <li>{@code com.github.yash777.securitycrypto.util} — {@link com.github.yash777.securitycrypto.util.IvUtils}</li>
 *   <li>{@code com.github.yash777.securitycrypto.exception} —
 *       {@link com.github.yash777.securitycrypto.exception.InvalidCiphertextException},
 *       {@link com.github.yash777.securitycrypto.exception.CryptoOperationException}</li>
 * </ul>
 *
 * @author Yash
 * @version 1.0.0
 */
package com.github.yash777.securitycrypto;
