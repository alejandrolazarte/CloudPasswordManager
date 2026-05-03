using CloudPasswordManager.Crypto.Models;

namespace CloudPasswordManager.Crypto.Interfaces;

/// <summary>
/// Core crypto contract. Implementations use Argon2id + HKDF + AES-256-GCM.
/// This interface must not expose algorithm details to callers.
/// </summary>
public interface IVaultCryptoService
{
    /// <summary>
    /// Derives the UnlockKey from master password, secret key and account salt.
    /// Master password MUST be UTF-8 NFC normalized before calling this method.
    /// </summary>
    UnlockKey DeriveUnlockKey(string masterPassword, byte[] secretKey, byte[] accountSalt);

    /// <summary>
    /// Encrypts a plain vault. Increments encryption_counter before encrypting.
    /// Nonce = nonce_prefix || encryption_counter (big-endian, 96 bits total).
    /// </summary>
    VaultEnvelope Encrypt(PlainVault vault, UnlockKey key, Guid accountId, byte[] accountSalt);

    /// <summary>
    /// Decrypts a vault envelope.
    /// Throws CryptographicException if ciphertext, tag or AAD has been tampered with.
    /// </summary>
    PlainVault Decrypt(VaultEnvelope envelope, UnlockKey key);
}